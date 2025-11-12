# TypeScript OAuth Server 

> **⚠️ Work in Progress**  
> This project is under development...

This is a sample OAuth server powered by Authlete APIs. This server is a Next.js full stack application that uses Authlete for OAuth/OIDC processing. It delegates all OAuth/OIDC processing to Authlete using [Authelte Typescript SDK](https://github.com/authlete/authlete-typescript-sdk).

## Overview

This samples demonstrates how to build a complete OAuth Server using:
- **Authlete**: For OAuth/OIDC protocol processing and token management.
- **Better Auth**: For authentication handling

The authentication is handled using Better-Auth. Currently, the user store is an in-memory store, but it can be extended to use various adapters in Better-Auth to store actual users in many different storage systems as supported by Better-Auth.

This server currently uses a few plugins for social authentication for a couple of social providers as well as for passkey authentication. Other authentication options can be configured by using additional plugins from Better-Auth and using additional components from Better-Auth-UI.

The whole authentication experience is completely customizable using the Better-Auth open source project, and the OAuth/OIDC functionalities are all controllable using Authlete.

## Getting Started

First, run the development server:

```bash
pnpm install 
pnpm dev
```
Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

# Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

