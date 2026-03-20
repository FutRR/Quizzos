export interface Tag {
    id: number;
    name: string;
    color?: string;
}

export interface CreateTagData {
    name: string;
    color?: string;
}
