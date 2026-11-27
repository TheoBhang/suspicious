import { z } from "zod";

export const fileSchema = z.object({
  context: z.string().optional(),
});

export type FileForm = z.infer<typeof fileSchema>;
