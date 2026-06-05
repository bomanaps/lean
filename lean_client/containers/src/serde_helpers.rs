// All previous helpers were callers of Serialize/Deserialize on production
// wire types; with those derives stripped the helpers have no remaining
// consumers. JSON parsing now lives in the `spec_test_fixtures` test-side
// wrappers, which carry their own hex/data-envelope handling.
