import { Tag, CreateTagData } from "../types/tagTypes";
import fetchClient from "../lib/fetchClient";

class TagService {
    async getAllTags(): Promise<Tag[]> {
        return fetchClient.get<Tag[]>("/tag");
    }

    async getTagById(id: number): Promise<Tag> {
        return fetchClient.get<Tag>(`/tag/${id}`);
    }

    async searchTags(query: string): Promise<Tag[]> {
        return fetchClient.get<Tag[]>(`/tag/search?query=${encodeURIComponent(query)}`);
    }

    async createTag(data: CreateTagData): Promise<Tag> {
        return fetchClient.post<Tag>("/tag", data);
    }

    async deleteTag(id: number): Promise<void> {
        return fetchClient.delete<void>(`/tag/${id}`);
    }
}

export default new TagService();
