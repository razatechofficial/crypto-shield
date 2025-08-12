-- Create some sample API usage data to make the dashboard more realistic
INSERT INTO api_usage (tenant_id, date, encryption_requests, key_rotations, threats_blocked) VALUES
('29d2b505-2353-4dbc-ba89-4115e5a4b4d5', CURRENT_DATE, 150000, 45, 12),
('29d2b505-2353-4dbc-ba89-4115e5a4b4d5', CURRENT_DATE - INTERVAL '1 day', 142000, 38, 8),
('29d2b505-2353-4dbc-ba89-4115e5a4b4d5', CURRENT_DATE - INTERVAL '2 days', 138000, 41, 15),
('29d2b505-2353-4dbc-ba89-4115e5a4b4d5', CURRENT_DATE - INTERVAL '3 days', 133000, 35, 9),
('29d2b505-2353-4dbc-ba89-4115e5a4b4d5', CURRENT_DATE - INTERVAL '4 days', 128000, 42, 11);