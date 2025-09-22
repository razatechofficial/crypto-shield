import { useQuery } from "@tanstack/react-query";
import type { User } from "@shared/schema";

export function useAuth() {
  const { data: user, isLoading, error } = useQuery<User>({
    queryKey: ["/api/auth/user"],
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
    // Don't throw on 401 errors - they're expected for unauthenticated users
    throwOnError: false,
  });

  // Consider 401 errors as "not authenticated" rather than an error state
  const isAuthenticated = !!user && !error;

  return {
    user,
    isLoading,
    isAuthenticated,
  };
}
