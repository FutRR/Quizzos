import fetchClient from "../lib/fetchClient";

import { MyUserProfile, BaseUser } from "../types/userTypes";

export interface UpdateProfileData {
    username?: string;
    email?: string;
    bio?: string;
}

class UserService {
    async getMyProfile(): Promise<MyUserProfile> {
        console.log("[UserService] getMyProfile() called");
        try {
            console.log("[UserService] Making GET request to /User/me...");
            const response = await fetchClient.get<MyUserProfile>("/User/me");
            console.log("[UserService] Response from /User/me:", response);
            return response;
        } catch (error) {
            console.error("[UserService] Error in getMyProfile():", error);
            throw error;
        }
    }

    async updateMyProfile(data: UpdateProfileData): Promise<MyUserProfile> {
        const response = await fetchClient.put<MyUserProfile>("/User/me", data);
        return response;
    }

    async getUserProfile(username: string): Promise<BaseUser> {
        const response = await fetchClient.get<BaseUser>(`/User/${username}`);
        return response;
    }
    
    async getAllUsers(): Promise<BaseUser[]> {
        const response = await fetchClient.get<BaseUser[]>(`/User/users`);
        return response;
    }
}

export default new UserService();
