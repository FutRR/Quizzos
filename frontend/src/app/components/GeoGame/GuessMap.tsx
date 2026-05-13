"use client";
import { useState } from "react";
import { MapContainer, TileLayer, Marker, useMapEvents } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";

// Fix marker icon paths (Webpack casse les chemins par défaut)
delete (L.Icon.Default.prototype as unknown as { _getIconUrl?: unknown })._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl:       "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl:     "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

function ClickHandler({ onPick }: { onPick: (lat: number, lng: number) => void }) {
  useMapEvents({ click(e) { onPick(e.latlng.lat, e.latlng.lng); } });
  return null;
}

export function GuessMap({ onSubmit }: { onSubmit: (lat: number, lng: number) => void }) {
  const [pick, setPick] = useState<{ lat: number; lng: number } | null>(null);
  return (
    <div className="flex flex-col gap-2">
      <MapContainer
        center={[20, 0]} zoom={2} scrollWheelZoom
        style={{ height: "50vh", width: "100%" }}
      >
        <TileLayer
          attribution='&copy; OpenStreetMap'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <ClickHandler onPick={(lat, lng) => setPick({ lat, lng })} />
        {pick && <Marker position={[pick.lat, pick.lng]} />}
      </MapContainer>
      <button
        disabled={!pick}
        onClick={() => pick && onSubmit(pick.lat, pick.lng)}
        className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
      >
        Valider ma proposition
      </button>
    </div>
  );
}