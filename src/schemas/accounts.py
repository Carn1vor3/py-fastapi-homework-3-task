from pydantic import (
    BaseModel,
    EmailStr,
    field_validator,
    Field
)


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(min_length=8)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str
