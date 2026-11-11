import { z } from 'zod';
import { insertUserSchema, users } from './schema';

export const errorSchemas = {
  internal: z.object({ message: z.string() }),
};

export const api = {
  tools: {
    searchUsers: {
      method: 'POST' as const,
      path: '/api/search' as const,
      responses: { 200: z.array(z.any()), 500: errorSchemas.internal },
    },
    ping: {
      method: 'POST' as const,
      path: '/api/ping' as const,
      input: z.object({ host: z.string() }),
      responses: { 200: z.object({ output: z.string() }), 500: errorSchemas.internal },
    },
    fetchUrl: {
      method: 'POST' as const,
      path: '/api/fetch' as const,
      input: z.object({ url: z.string() }),
      responses: { 200: z.object({ data: z.string() }), 500: errorSchemas.internal },
    },
    readLog: {
      method: 'GET' as const,
      path: '/api/files' as const,
      responses: { 200: z.object({ content: z.string() }), 500: errorSchemas.internal },
    },
    deserialize: {
      method: 'POST' as const,
      path: '/api/admin/config' as const,
      input: z.object({ data: z.string() }),
      responses: { 200: z.object({ result: z.any() }), 500: errorSchemas.internal },
    },
    updateProfile: {
      method: 'POST' as const,
      path: '/api/profile/update' as const,
      input: z.object({ bio: z.string() }),
      responses: { 200: z.object({ message: z.string() }), 500: errorSchemas.internal },
    },
    debugInfo: {
      method: 'GET' as const,
      path: '/api/debug' as const,
      responses: { 200: z.object({ env: z.any() }), 500: errorSchemas.internal },
    },
    bypassAuth: {
      method: 'GET' as const,
      path: '/api/admin/stats' as const,
      responses: { 200: z.object({ stats: z.any() }), 401: z.object({ message: z.string() }) },
    },
    viewInvoice: {
      method: 'GET' as const,
      path: '/api/invoice/:id' as const,
      responses: { 200: z.object({ id: z.number(), amount: z.string(), status: z.string() }), 404: errorSchemas.internal },
    },
    deactivateUser: {
      method: 'POST' as const,
      path: '/api/admin/deactivate' as const,
      input: z.object({ userId: z.number() }),
      responses: { 200: z.object({ message: z.string() }), 500: errorSchemas.internal },
    },
    redirect: {
      method: 'GET' as const,
      path: '/api/redirect' as const,
      responses: { 302: z.object({ location: z.string() }), 400: errorSchemas.internal },
    },
    calculateDiscount: {
      method: 'POST' as const,
      path: '/api/checkout/discount' as const,
      input: z.object({ baseAmount: z.number(), coupons: z.array(z.string()) }),
      responses: { 200: z.object({ finalAmount: z.number(), breakdown: z.any() }), 500: errorSchemas.internal },
    },
    randomToken: {
      method: 'GET' as const,
      path: '/api/generate-token' as const,
      responses: { 200: z.object({ token: z.string() }) },
    },
    processFile: {
      method: 'POST' as const,
      path: '/api/process-file' as const,
      input: z.object({ filename: z.string(), operations: z.array(z.any()) }),
      responses: { 200: z.object({ result: z.string() }), 500: errorSchemas.internal },
    },
  },

  billing: {
    getStatus: {
      method: 'GET' as const,
      path: '/api/billing/:userId' as const,
      responses: {
        200: z.object({
          userId: z.number(),
          username: z.string(),
          plan: z.string(),
          walletBalance: z.string(),
          planStartDate: z.string().nullable(),
        }),
        404: errorSchemas.internal,
      },
    },
    upgrade: {
      method: 'POST' as const,
      path: '/api/subscription/upgrade' as const,
      input: z.object({ userId: z.number(), targetPlan: z.string(), paymentMethod: z.string() }),
      responses: {
        200: z.object({ message: z.string(), plan: z.string(), walletBalance: z.string() }),
        500: errorSchemas.internal,
      },
    },
    downgrade: {
      method: 'POST' as const,
      path: '/api/subscription/downgrade' as const,
      input: z.object({ userId: z.number().int().optional(), targetPlan: z.enum(['free', 'pro', 'enterprise']) }),
      responses: {
        200: z.object({ message: z.string(), refundAmount: z.number(), walletBalance: z.string() }),
        500: errorSchemas.internal,
      },
    },
    applyCredits: {
      method: 'POST' as const,
      path: '/api/subscription/apply-credits' as const,
      input: z.object({ userId: z.number(), orderAmount: z.number() }),
      responses: {
        200: z.object({ message: z.string(), finalAmount: z.number(), creditsUsed: z.number() }),
        500: errorSchemas.internal,
      },
    },
    topup: {
      method: 'POST' as const,
      path: '/api/wallet/topup' as const,
      input: z.object({ userId: z.number(), amount: z.number() }),
      responses: {
        200: z.object({ message: z.string(), walletBalance: z.string() }),
        500: errorSchemas.internal,
      },
    },
  },
};

export function buildUrl(path: string, params?: Record<string, string | number>): string {
  let url = path;
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (url.includes(`:${key}`)) url = url.replace(`:${key}`, String(value));
    });
  }
  return url;
}
