import Ajv, { AnySchema, ValidateFunction } from "ajv";

const ajv = new Ajv({
  allErrors: true,
  coerceTypes: false,
  strict: false,
});

const compiledSchemas = new Map<string, ValidateFunction>();

export interface SchemaValidationResult {
  valid: boolean;
  errors?: string[];
}

/**
 * Validates tool call arguments against a JSON Schema using Ajv.
 * Rejects invalid types, missing required properties, or unexpected properties before execution.
 */
export function validateToolArgs(
  schema: Record<string, unknown>,
  args: unknown,
  schemaName?: string
): SchemaValidationResult {
  if (!schema || Object.keys(schema).length === 0) {
    return { valid: true };
  }

  try {
    let validator: ValidateFunction;
    const cacheKey = schemaName ?? JSON.stringify(schema);

    if (compiledSchemas.has(cacheKey)) {
      validator = compiledSchemas.get(cacheKey)!;
    } else {
      validator = ajv.compile(schema as AnySchema);
      compiledSchemas.set(cacheKey, validator);
    }

    const valid = validator(args);
    if (!valid && validator.errors) {
      const errors = validator.errors.map((e) => {
        const path = e.instancePath ? `property '${e.instancePath.slice(1)}'` : "root arguments";
        return `${path} ${e.message}`;
      });
      return { valid: false, errors };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, errors: [`Schema compilation/validation error: ${String(err)}`] };
  }
}
