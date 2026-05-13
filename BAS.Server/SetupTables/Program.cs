using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Runtime;

namespace SetupTables
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var region = Amazon.RegionEndpoint.GetBySystemName("ap-south-1");
            var client = new AmazonDynamoDBClient(region);
            
            Console.WriteLine("Creating TenantsMetadata...");
            await CreateTableIfNotExists(client, "TenantsMetadata", 
                new List<KeySchemaElement> { new KeySchemaElement("TenantId", KeyType.HASH) }, 
                new List<AttributeDefinition> { 
                    new AttributeDefinition("TenantId", ScalarAttributeType.S),
                    new AttributeDefinition("Email", ScalarAttributeType.S)
                },
                new List<GlobalSecondaryIndex> {
                    new GlobalSecondaryIndex {
                        IndexName = "EmailIndex",
                        KeySchema = new List<KeySchemaElement> { new KeySchemaElement("Email", KeyType.HASH) },
                        Projection = new Projection { ProjectionType = ProjectionType.ALL }
                    }
                }
            );

            Console.WriteLine("Creating Agents...");
            await CreateTableIfNotExists(client, "Agents", 
                new List<KeySchemaElement> { 
                    new KeySchemaElement("TenantId", KeyType.HASH),
                    new KeySchemaElement("AgentId", KeyType.RANGE)
                }, 
                new List<AttributeDefinition> { 
                    new AttributeDefinition("TenantId", ScalarAttributeType.S),
                    new AttributeDefinition("AgentId", ScalarAttributeType.S)
                });

            Console.WriteLine("Creating Tenants...");
            await CreateTableIfNotExists(client, "Tenants", 
                new List<KeySchemaElement> { 
                    new KeySchemaElement("TenantId", KeyType.HASH),
                    new KeySchemaElement("AgentId", KeyType.RANGE)
                }, 
                new List<AttributeDefinition> { 
                    new AttributeDefinition("TenantId", ScalarAttributeType.S),
                    new AttributeDefinition("AgentId", ScalarAttributeType.S)
                });

            Console.WriteLine("Completed waiting for tables to become active.");
        }

        static async Task CreateTableIfNotExists(AmazonDynamoDBClient client, string tableName, List<KeySchemaElement> keySchema, List<AttributeDefinition> attributes, List<GlobalSecondaryIndex> gsis = null)
        {
            try
            {
                var request = new CreateTableRequest
                {
                    TableName = tableName,
                    AttributeDefinitions = attributes,
                    KeySchema = keySchema,
                    BillingMode = BillingMode.PAY_PER_REQUEST
                };

                if (gsis != null)
                {
                    request.GlobalSecondaryIndexes = gsis;
                }

                await client.CreateTableAsync(request);
                Console.WriteLine($"Table {tableName} creation initiated.");
            }
            catch (ResourceInUseException)
            {
                Console.WriteLine($"Table {tableName} already exists or is being created.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating {tableName}: {ex.Message}");
            }
        }
    }
}
