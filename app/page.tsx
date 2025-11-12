"use client";
import { UserRoundIcon } from "lucide-react";

import { authClient } from "@/lib/auth-client";
import Link from "next/link";

export default function Home() {

  const { data: session } = authClient.useSession();
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        {session?.user ? (
          <h1 className="text-2xl font-medium">
          Welcome, {session.user.name || session.user.email}
        </h1>
        ) : (
        <h1 className="text-2xl font-medium flex items-center justify-center gap-2 mb-2">
          Click <UserRoundIcon className="h-6 w-6" /> to test auth
        </h1>
        )}
      </div>
 
      <Link href="/o/az" className="text-blue-500">Authorize</Link>
 
    </div>
  );
}
