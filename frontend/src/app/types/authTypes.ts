export interface LoginRequest {
    username: string;
    password: string;
    audience: string;
}
export interface RegisterRequest {
    username: string;
    email: string;
    password: string;
    displayName: string;
}
export interface ApiError {
    message: string;
    statusCode: number;
    error?: string;
}