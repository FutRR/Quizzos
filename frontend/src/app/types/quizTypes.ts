import { Tag } from "./tagTypes";

export interface Quiz {
    id: string;
    authorId: string;
    title: string;
    description: string;
    difficulty: string;
    tags: Tag[];
    imageUrl: string;
    createdAt: string;
    updatedAt: string;
}