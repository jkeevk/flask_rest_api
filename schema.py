from pydantic import BaseModel, field_validator
import re


class BaseUser(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        if len(value) < 8:
            raise ValueError("Password is too short, it must be at least 8 characters.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit.")

        return value


class BaseAdvert(BaseModel):
    title: str
    description: str
    owner_id: int

    @field_validator("title")
    @classmethod
    def check_title(cls, value: str):
        if len(value) < 10:
            raise ValueError("Title is too short, it must be at least 10 characters.")
        return value

    @field_validator("description")
    @classmethod
    def check_description(cls, value: str):
        if len(value) < 10:
            raise ValueError(
                "Description is too short, it must be at least 10 characters."
            )
        return value


class CreateUser(BaseUser):
    email: str
    password: str


class UpdateUser(BaseUser):
    email: str = None
    password: str = None


class CreateAdvert(BaseAdvert):
    title: str
    description: str
    owner_id: int


class UpdateAdvert(BaseAdvert):
    title: str = None
    description: str = None
    owner_id: int = None
