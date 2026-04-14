import { useQuery } from "@tanstack/react-query";
import { authApi } from "../lib/api";

export function useAuth() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["auth", "me"],
    queryFn: authApi.me,
    retry: false,
    staleTime: 5 * 60_000,
  });

  return {
    user: data ?? null,
    isLoading,
    isAuthenticated: !!data && !error,
  };
}
