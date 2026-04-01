"use client";

import { useState } from "react";
import Image from "next/image";
import fetchClient from "@/app/lib/fetchClient";

interface ImageUploadProps {
  onImageUploaded: (url: string) => void;
  currentImageUrl?: string;
}

export default function ImageUpload({
  onImageUploaded,
  currentImageUrl,
}: ImageUploadProps) {
  const [preview, setPreview] = useState<string | null>(
    currentImageUrl || null,
  );
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validation côté client
    if (file.size > 5 * 1024 * 1024) {
      setError("File size must be less than 5MB");
      return;
    }

    if (!file.type.startsWith("image/")) {
      setError("Please select an image file");
      return;
    }

    setError(null);

    // Preview local
    const reader = new FileReader();
    reader.onloadend = () => {
      setPreview(reader.result as string);
    };
    reader.readAsDataURL(file);

    // Upload vers l'API
    await uploadImage(file);
  };

  const uploadImage = async (file: File) => {
    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const data = await fetchClient.postFormData<{ imageUrl: string }>(
        "/Upload/image",
        formData,
      );

      onImageUploaded(data.imageUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setPreview(null);
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileChange({ target: { files: [file] } } as any);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2">
        <label htmlFor="image-upload" className="font-medium">
          Image
        </label>

        {/* Zone de drag & drop */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          className={`
            relative border-2 border-dashed rounded-lg p-8 text-center transition-colors
            ${
              isDragging
                ? "border-blue-500 bg-blue-50"
                : "border-gray-300 hover:border-gray-400"
            }
            ${uploading ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
          `}
        >
          <input
            id="image-upload"
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            disabled={uploading}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />

          <div className="flex flex-col items-center gap-2">
            <svg
              className="w-12 h-12 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>
            <div className="text-sm text-gray-600">
              <span className="font-semibold text-blue-600">
                Click to upload
              </span>{" "}
              or drag and drop
            </div>
            <div className="text-xs text-gray-500">
              PNG, JPG, GIF, WebP up to 5MB
            </div>
          </div>
        </div>
      </div>

      {error && <div className="text-red-600 text-sm">{error}</div>}

      {uploading && <div className="text-blue-600 text-sm">Uploading...</div>}

      {preview && (
        <div className="relative w-full max-w-md h-48 border rounded overflow-hidden">
          <Image src={preview} alt="Preview" fill className="object-cover" />
        </div>
      )}
    </div>
  );
}
