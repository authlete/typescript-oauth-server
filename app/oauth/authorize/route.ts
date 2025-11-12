import {auth} from "@/lib/auth";
import { headers } from "next/headers";

export async function GET(request: Request) { 
   
    const headersList = await headers();
    const session = await auth.api.getSession({
        headers: headersList
    });
    
    if (!session) {
        return Response.json({ route: "/authorize", nextStep: "No Session Found" });
        //return Response.redirect(new URL("/auth/sign-in", request.url));
    }
    //Todo: Proxy to authlete. 
    return Response.json({ route: "/authorize", nextStep: "Proxy to authlete" });
}