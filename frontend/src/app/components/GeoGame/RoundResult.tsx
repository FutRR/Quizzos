"use client";
import { MapContainer, TileLayer, Marker, Polyline, Tooltip } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import { GuessResultDto } from "../../types/geoGameTypes";

const coloredIcon = (color: string) =>
  new L.Icon({
    iconUrl: `https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-${color}.png`,
    iconRetinaUrl: `https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-${color}.png`,
    shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    shadowSize: [41, 41],
  });

const actualIcon = coloredIcon("green");
const guessIcon = coloredIcon("red");

interface Props {
  result: GuessResultDto;
  guessLat: number;
  guessLng: number;
  onNext: () => void;
}

export function RoundResult({ result, guessLat, guessLng, onNext }: Props) {
  const center: [number, number] = [
    (result.actualLat + guessLat) / 2,
    (result.actualLng + guessLng) / 2,
  ];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-between text-lg">
        <span>Distance : <b>{result.distanceKm.toFixed(1)} km</b></span>
        <span>Score : <b>{result.score} / 5000</b></span>
      </div>
      <div className="flex gap-4 text-sm">
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-green-600" /> Vraie position</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-red-600" /> Votre proposition</span>
      </div>
      <MapContainer center={center} zoom={3} style={{ height: "50vh", width: "100%" }}>
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        <Marker position={[result.actualLat, result.actualLng]} icon={actualIcon}>
          <Tooltip permanent direction="top" offset={[0, -30]}>Vraie position</Tooltip>
        </Marker>
        <Marker position={[guessLat, guessLng]} icon={guessIcon}>
          <Tooltip permanent direction="top" offset={[0, -30]}>Votre proposition</Tooltip>
        </Marker>
        <Polyline positions={[[result.actualLat, result.actualLng], [guessLat, guessLng]]} pathOptions={{ color: "#1f2937", dashArray: "6 6" }} />
      </MapContainer>
      <button onClick={onNext} className="px-4 py-2 bg-blue-600 text-white rounded">
        Manche suivante
      </button>
    </div>
  );
}