// Response schema for GET /oathkeeper/handlers. A handler descriptor is the
// plain-language shape the admin UI renders (label/description + guided fields);
// an explicit schema keeps fast-json-stringify from stripping nested fields.
const handlerDescriptorJsonSchema = {
  type: 'object',
  properties: {
    handler: { type: 'string' },
    label: { type: 'string' },
    description: { type: 'string' },
    hasFreeformConfig: { type: 'boolean' },
    fields: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string' },
          label: { type: 'string' },
          type: {
            type: 'string',
            enum: ['string', 'url', 'bool', 'textarea', 'kv', 'list', 'json'],
          },
          required: { type: 'boolean' },
          placeholder: { type: 'string' },
          help: { type: 'string' },
        },
        required: ['key', 'label', 'type'],
      },
    },
  },
  required: ['handler', 'label', 'description', 'hasFreeformConfig', 'fields'],
}

export const oathkeeperHandlerCatalogJsonSchema = {
  type: 'object',
  properties: {
    authenticators: { type: 'array', items: handlerDescriptorJsonSchema },
    authorizers: { type: 'array', items: handlerDescriptorJsonSchema },
    mutators: { type: 'array', items: handlerDescriptorJsonSchema },
    errorHandlers: { type: 'array', items: handlerDescriptorJsonSchema },
  },
  required: ['authenticators', 'authorizers', 'mutators', 'errorHandlers'],
}
