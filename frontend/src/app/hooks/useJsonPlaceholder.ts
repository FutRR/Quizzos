import { useState, useEffect } from "react";

export const useJsonPlaceholder = () => {
  const [user, setUser] = useState<any>(null);
  const [images, setImages] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetch("https://jsonplaceholder.typicode.com/users/1")
      .then(response => response.json())
      .then(data => setUser(data))
      .catch(err => console.error("Erreur user:", err));
  }, []);
  
  useEffect(() => {
    // Limiter à 10 photos au lieu de 5000
    fetch("https://jsonplaceholder.typicode.com/photos?_limit=10")
      .then(response => response.json())
      .then(data => {
        setImages(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Erreur images:", err);
        setLoading(false);
      });
  }, []);
  
  return {user, images, loading};
}