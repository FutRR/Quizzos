import { BaseUser } from "./userTypes";

export type User = BaseUser;

export interface LoginRequest {
    username: string;
    password: string;
    audience: string;
}
export interface RegisterRequest {
    username: string;
    email: string;
    password: string;
}
export interface AuthResponse {
    user: User;
    token: string;
}
export interface ApiError {
    message: string;
    statusCode: number;
    error?: string;
}