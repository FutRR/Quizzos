"use client";
import { useEffect, useRef } from "react";
import { Viewer } from "mapillary-js";
import "mapillary-js/dist/mapillary.css";

export function StreetView({ imageId }: { imageId: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const viewer = new Viewer({
      accessToken: process.env.NEXT_PUBLIC_MAPILLARY_CLIENT_TOKEN!,
      container: ref.current,
      imageId,
      component: { cover: false },
    });
    return () => viewer.remove();
  }, [imageId]);
  return <div ref={ref} className="w-full h-[70vh] rounded-lg overflow-hidden" />;
}