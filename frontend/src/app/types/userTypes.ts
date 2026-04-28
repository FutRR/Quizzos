export interface BaseUser {
    id?: string;
    userName: string;
    displayName: string;
    createdAt: string;
    avatarUrl?: string;
}

export interface MyUserProfile extends BaseUser {
    isEmailVerified: boolean;
    email: string;
}