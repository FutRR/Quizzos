export interface BaseUser {
    id: string;
    username: string;   
    createdAt: string;
}

export interface MyUserProfile extends BaseUser {
    emailVerified: boolean;
    email: string;
}