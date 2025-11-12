"use client"

import { AuthUIProvider } from "@daveyplate/better-auth-ui"
import Link from "next/link"
import { useRouter } from "next/navigation"
import type { ReactNode } from "react"
import { authClient } from "@/lib/auth-client"

export function Providers({ children }: { children: ReactNode }) {
    const router = useRouter()

    return (
        <AuthUIProvider
            authClient={authClient}
            navigate={router.push}
            replace={router.replace}
            onSessionChange={() => router.refresh()}
            passkey={true}
            social={{
                providers: ["github", "google"]
            }}
            multiSession
            //   //magicLink
            //   avatar={{
            //     upload: async (file) => {
            //       const formData = new FormData()
            //       formData.append("avatar", file)
            //       const res = await fetch("/api/uploadAvatar", { method: "POST", body: formData })
            //       const { data } = await res.json()
            //       return data.url
            //     },
            //     delete: async (url) => {
            //       await fetch("/api/deleteAvatar", {
            //         method: "POST",
            //         headers: { "Content-Type": "application/json" },
            //         body: JSON.stringify({ url })
            //       })
            //     },
            //     // Custom Image component for rendering avatar images
            //     // Useful for CDN optimization (Cloudinary, Imgix, ImgProxy, etc.)
            //    Image: Image // Use Next.js Image component for avatars
            //   }}
            //   captcha={{
            //     provider: "google-recaptcha-v3",
            //     siteKey: "your-site-key",
            //   }}
            //   settings={{
            //     url: "/dashboard/settings"
            //   }}
            twoFactor={["otp", "totp"]}
            Link={Link}
        >
            {children}
        </AuthUIProvider>

    )
}