from datetime import datetime, timezone, timedelta
from typing import cast
from jose import JWTError
import secrets
from fastapi import APIRouter, Depends, status, HTTPException, Body
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema
from schemas.accounts import (
    UserResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter(prefix="", tags=["Accounts"])


def generate_token() -> str:
    return secrets.token_urlsafe(32)


@router.post(
    "/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        existing_user_query = await db.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        existing_user = existing_user_query.scalar_one_or_none()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group_query = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = group_query.scalar_one_or_none()
        if not group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found.",
            )

        new_user = UserModel(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            is_active=False,
            group_id=group.id,
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            token=generate_token(),
            user_id=cast(int, new_user.id),
            expires_at=(datetime.utcnow() + timedelta(hours=24)).replace(
                tzinfo=timezone.utc
            ),
        )
        db.add(activation_token)
        await db.commit()

        return UserResponseSchema(id=new_user.id, email=new_user.email)

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(
    data: UserActivationRequestSchema = Body(...),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        token_result = await db.execute(
            select(ActivationTokenModel).where(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == data.token,
            )
        )
        token_record = token_result.scalar_one_or_none()

        if not token_record or cast(datetime, token_record.expires_at).replace(
            tzinfo=timezone.utc
        ) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True

        await db.delete(token_record)
        await db.commit()

        return {"message": "User account activated successfully."}

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset_token(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = user_result.scalar_one_or_none()

        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )

            reset_token = PasswordResetTokenModel(
                token=generate_token(),
                user_id=cast(int, user.id),
                expires_at=(datetime.utcnow() + timedelta(hours=1)).replace(
                    tzinfo=timezone.utc
                ),
            )
            db.add(reset_token)
            await db.commit()

    except Exception:
        await db.rollback()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
    data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token_result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == data.token,
            )
        )
        token_record = token_result.scalar_one_or_none()

        if not token_record or cast(datetime, token_record.expires_at).replace(
            tzinfo=timezone.utc
        ) < datetime.now(timezone.utc):
            if token_record:
                await db.delete(token_record)
                await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.hashed_password = hash_password(data.password)

        await db.delete(token_record)

        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        user = result.scalar_one_or_none()

        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token = jwt_manager.create_access_token(
            subject=str(user.id), expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
        )

        refresh_token_str = jwt_manager.create_refresh_token(
            subject=str(user.id),
            expires_delta=timedelta(
                days=settings.LOGIN_TIME_DAYS * 30
            ),  # Наприклад, 30 днів
        )

        refresh_token = RefreshTokenModel.create(
            token=refresh_token_str,
            user_id=cast(int, user.id),
            expires_at=(
                datetime.utcnow() + timedelta(days=settings.LOGIN_TIME_DAYS * 30)
            ).replace(tzinfo=timezone.utc),
        )
        db.add(refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/api/v1/accounts/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token."
            )
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    token_result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    token_record = token_result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == cast(int, user_id))
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
    )

    return TokenRefreshResponseSchema(access_token=new_access_token)
