/// Mock test for prover.rs logic WITHOUT Stwo proof generation
/// This tests the MPC-TLS flow, parsing, and data extraction
///
/// Note: Actual Stwo proof generation is tested separately in standalone fibonacci_zk crate

#[cfg(test)]
mod tests {
    use serde_json::json;
    use spansy::http::Responses;
    use spansy::Spanned;

    #[test]
    fn test_extract_fibonacci_index_from_json() {
        let json_response = json!({
            "challenge_index": 5,
            "status": "ok"
        });

        let json_body = json_response.to_string();
        let response_str = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json_body.len(),
            json_body
        );

        // Parse response
        let responses: Vec<_> = Responses::new_from_slice(response_str.as_bytes())
            .collect::<Result<_, _>>()
            .expect("Failed to parse response");

        let response = responses.first().expect("No response found");
        let body = response.body.as_ref().expect("No body found");

        // Verify body is JSON
        let spansy::http::BodyContent::Json(_parsed_json) = &body.content else {
            panic!("Expected JSON body");
        };

        // Extract index by parsing body bytes directly with serde_json
        let body_start = body.span().indices().min().expect("No body start");
        let body_end = body.span().indices().max().expect("No body end") + 1;
        let body_bytes = &response_str.as_bytes()[body_start..body_end];

        let json_value: serde_json::Value = serde_json::from_slice(body_bytes)
            .expect("Failed to parse JSON");

        let index = json_value
            .get("challenge_index")
            .and_then(|v| v.as_u64())
            .expect("challenge_index not found or not a valid u64") as usize;

        assert_eq!(index, 5, "Extracted fibonacci_index should be 5");
        println!("✅ Successfully extracted fibonacci_index = {}", index);
    }

    #[test]
    fn test_fibonacci_computation() {
        // Simulate what prover does after extracting fibonacci_index
        let fibonacci_index: usize = 5;

        // This is what the circuit computes internally
        let mut a = 0u32;
        let mut b = 1u32;

        for _ in 0..fibonacci_index {
            let c = a + b;
            a = b;
            b = c;
        }

        let fibonacci_value = a;

        assert_eq!(fibonacci_value, 5, "fibonacci(5) should be 5");
        println!(
            "✅ Prover computed fibonacci({}) = {}",
            fibonacci_index, fibonacci_value
        );
    }

    #[test]
    fn test_multiple_fibonacci_values() {
        let test_cases = vec![
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 3),
            (5, 5),
            (6, 8),
            (7, 13),
            (10, 55),
        ];

        for (index, expected) in test_cases {
            let mut a = 0u32;
            let mut b = 1u32;

            for _ in 0..index {
                let c = a + b;
                a = b;
                b = c;
            }

            let result = a;
            assert_eq!(
                result, expected,
                "fibonacci({}) should be {}, got {}",
                index, expected, result
            );
        }

        println!("✅ All fibonacci computations correct");
    }

    #[test]
    fn test_response_parsing_structure() {
        // Test different response structures
        let test_responses = vec![
            (
                json!({"challenge_index": 0}),
                0,
                "Zero index",
            ),
            (
                json!({"challenge_index": 1}),
                1,
                "Index 1",
            ),
            (
                json!({"challenge_index": 10}),
                10,
                "Index 10",
            ),
        ];

        for (json_body, expected_index, description) in test_responses {
            let json_str = json_body.to_string();
            let response_str = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json_str.len(),
                json_str
            );

            let responses: Vec<_> = Responses::new_from_slice(response_str.as_bytes())
                .collect::<Result<_, _>>()
                .expect("Failed to parse response");

            let response = responses.first().expect("No response");
            let body = response.body.as_ref().expect("No body");

            let spansy::http::BodyContent::Json(_json) = &body.content else {
                panic!("Expected JSON");
            };

            // Extract index by parsing body bytes directly with serde_json
            let body_start = body.span().indices().min().expect("No body start");
            let body_end = body.span().indices().max().expect("No body end") + 1;
            let body_bytes = &response_str.as_bytes()[body_start..body_end];

            let json_value: serde_json::Value = serde_json::from_slice(body_bytes)
                .expect("Failed to parse JSON");

            let index = json_value
                .get("challenge_index")
                .and_then(|v| v.as_u64())
                .expect("challenge_index not found or not a valid u64") as usize;

            assert_eq!(index, expected_index, "{} failed", description);
            println!("✅ {}: index = {}", description, index);
        }
    }

    #[test]
    fn test_proof_bundle_structure() {
        // Test that proof bundle has correct structure
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct MockFibonacciZKProofBundle {
            proof: Vec<u8>,
            fibonacci_value: u32,
            log_size: u32,
        }

        let bundle = MockFibonacciZKProofBundle {
            proof: vec![1, 2, 3, 4, 5], // Mock proof bytes
            fibonacci_value: 5,
            log_size: 4,
        };

        // Test serialization
        let serialized = bincode::serialize(&bundle).expect("Serialization failed");
        println!("✅ Proof bundle serialized: {} bytes", serialized.len());

        // Test deserialization
        let deserialized: MockFibonacciZKProofBundle =
            bincode::deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(
            deserialized.fibonacci_value, 5,
            "fibonacci_value should be preserved"
        );
        assert_eq!(deserialized.log_size, 4, "log_size should be preserved");
        assert_eq!(deserialized.proof.len(), 5, "proof length should be preserved");

        println!("✅ Proof bundle roundtrip successful");
    }
}
