export async function POST(request: Request) { 
    //Todo: Proxy to authlete. 
    
    return Response.json({ route: "/token", nextStep: "Proxy to authlete" });
    
}