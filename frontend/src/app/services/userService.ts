import fetchClient from "../lib/fetchClient";

import { MyUserProfile, BaseUser } from "../types/userTypes";

export interface UpdateProfileData {
    username?: string;
    email?: string;
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
        console.log("[UserService] getUserProfile() called with username:", username);
        try {
            console.log("[UserService] Making GET request to /User/" + username);
            const response = await fetchClient.get<BaseUser>("/User/" + username);
            console.log("[UserService] Response from /User/" + username + ":", response);
            return response;
        } catch (error) {
            console.error("[UserService] Error in getUserProfile():", error);
            throw error;
        }
    }
    
    async getAllUsers(): Promise<BaseUser[]> {
        const response = await fetchClient.get<BaseUser[]>(`/User/users`);
        return response;
    }

    async logout(): Promise<void> {
        await fetchClient.post("/Auth/logout");
    }
}

export default new UserService();
