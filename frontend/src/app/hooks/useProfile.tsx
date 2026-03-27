import { useCallback, useState, useEffect } from "react";
import userService from "../services/userService";

export function useProfile() {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateMyProfile = useCallback(async (data: any) => {
    try {
      setLoading(true);
      setError(null);
      const response = await userService.updateMyProfile(data);
      setProfile(response);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { profile, loading, error, updateMyProfile };
}
