import { AuthView } from "@daveyplate/better-auth-ui"
import { authViewPaths } from "@daveyplate/better-auth-ui/server"

export const dynamicParams = false

export function generateStaticParams() {
    return Object.values(authViewPaths).map((path) => ({ path }))
}

export default async function AuthPage({ params }: { params: Promise<{ path: string }> }) {
    const { path } = await params
    
    return (
        <main className="a-sign-in-page flex min-h-screen w-full flex-col items-center justify-center">
            <div className="a-sign-in-content flex w-full max-w-md flex-col items-center justify-center px-4 py-8 md:max-w-lg md:px-6 md:py-12 lg:max-w-xl">
                <AuthView path={path} />
            </div>
        </main>
    )
}

