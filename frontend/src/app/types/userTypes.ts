export interface BaseUser {
    id?: string;
    userName: string;
    createdAt: string;
    avatarUrl?: string;
}

export interface MyUserProfile extends BaseUser {
    isEmailVerified: boolean;
    email: string;
}