export interface BaseUser {
    id?: string;
    userName: string;
    createdAt: Date;
}

export interface MyUserProfile extends BaseUser {
    isEmailVerified: boolean;
    email: string;
}