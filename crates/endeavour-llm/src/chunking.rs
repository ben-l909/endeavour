use crate::context::estimate_text_tokens;

pub const DEFAULT_CHUNK_MAX_TOKENS: usize = 2_000;
pub const DEFAULT_CHUNK_OVERLAP_TOKENS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub text: String,
    pub index: usize,
    pub total: usize,
    pub line_start: usize,
    pub line_end: usize,
}

pub struct FunctionChunker;

impl FunctionChunker {
    pub fn chunk(decompiled: &str, max_tokens: usize, overlap_tokens: usize) -> Vec<Chunk> {
        if decompiled.is_empty() {
            return vec![Chunk {
                text: String::new(),
                index: 0,
                total: 1,
                line_start: 0,
                line_end: 0,
            }];
        }

        if max_tokens == 0 {
            return vec![Chunk {
                text: String::new(),
                index: 0,
                total: 1,
                line_start: 0,
                line_end: 0,
            }];
        }

        let lines: Vec<&str> = decompiled.split_inclusive('\n').collect();
        let line_tokens: Vec<usize> = lines
            .iter()
            .map(|line| estimate_text_tokens(line))
            .collect();
        let total_tokens: usize = line_tokens.iter().sum();

        if total_tokens <= max_tokens {
            return vec![Chunk {
                text: decompiled.to_string(),
                index: 0,
                total: 1,
                line_start: 1,
                line_end: lines.len(),
            }];
        }

        let mut spans = Vec::new();
        let mut start = 0;

        while start < lines.len() {
            let mut end = start;
            let mut chunk_tokens = 0;

            while end < lines.len() {
                let next_tokens = line_tokens[end];
                if chunk_tokens + next_tokens > max_tokens && end > start {
                    break;
                }

                chunk_tokens += next_tokens;
                end += 1;

                if chunk_tokens >= max_tokens {
                    break;
                }
            }

            spans.push((start, end));

            if end >= lines.len() {
                break;
            }

            let overlap_start = overlap_start_line(&line_tokens, start, end, overlap_tokens);
            if overlap_start <= start {
                start = end;
            } else {
                start = overlap_start;
            }
        }

        let total = spans.len();
        spans
            .into_iter()
            .enumerate()
            .map(|(index, (start, end))| Chunk {
                text: lines[start..end].concat(),
                index,
                total,
                line_start: start + 1,
                line_end: end,
            })
            .collect()
    }
}

fn overlap_start_line(
    line_tokens: &[usize],
    chunk_start: usize,
    chunk_end: usize,
    overlap_tokens: usize,
) -> usize {
    if overlap_tokens == 0 {
        return chunk_end;
    }

    let mut overlap_sum = 0;
    let mut start = chunk_end;

    while start > chunk_start && overlap_sum < overlap_tokens {
        overlap_sum += line_tokens[start - 1];
        start -= 1;
    }

    if start == chunk_start {
        if chunk_end.saturating_sub(chunk_start) > 1 {
            chunk_start + 1
        } else {
            chunk_end
        }
    } else {
        start
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionChunker;
    use crate::estimate_text_tokens;

    #[test]
    fn small_function_returns_single_chunk_unchanged() {
        let code = "int add(int a, int b) {\n    return a + b;\n}\n";
        let chunks = FunctionChunker::chunk(code, 200, 20);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].total, 1);
        assert_eq!(chunks[0].line_start, 1);
        assert_eq!(chunks[0].line_end, 3);
        assert_eq!(chunks[0].text, code);
    }

    #[test]
    fn large_function_is_split_into_multiple_line_aligned_chunks() {
        let mut code = String::new();
        for i in 0..100 {
            code.push_str(&format!("    v{} = arg{} + 0x1234;\n", i, i));
        }

        let chunks = FunctionChunker::chunk(&code, 70, 10);

        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(estimate_text_tokens(&chunk.text) <= 70);
            assert_eq!(chunk.total, chunks.len());
            assert!(chunk.line_start >= 1);
            assert!(chunk.line_end >= chunk.line_start);
        }
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[chunks.len() - 1].index, chunks.len() - 1);
    }

    #[test]
    fn adjacent_chunks_include_overlapping_lines() {
        let mut code = String::new();
        for i in 0..60 {
            code.push_str(&format!("line_{:03}: out = in + {} + 0xdeadbeef;\n", i, i));
        }

        let chunks = FunctionChunker::chunk(&code, 80, 20);
        assert!(chunks.len() > 1);
        for window in chunks.windows(2) {
            let left = &window[0];
            let right = &window[1];

            assert!(right.line_start <= left.line_end);
            assert!(right.line_start > left.line_start);
        }
    }

    #[test]
    fn empty_input_returns_single_empty_chunk() {
        let chunks = FunctionChunker::chunk("", 100, 10);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].total, 1);
        assert!(chunks[0].text.is_empty());
        assert_eq!(chunks[0].line_start, 0);
        assert_eq!(chunks[0].line_end, 0);
    }

    #[test]
    fn single_line_function_splits_without_midline_breaks() {
        let code = "int giant = 0x123456789abcdef0123456789abcdef0123456789abcdef;";
        let chunks = FunctionChunker::chunk(code, 4, 2);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, code);
        assert_eq!(chunks[0].line_start, 1);
        assert_eq!(chunks[0].line_end, 1);
    }

    #[test]
    fn all_blank_lines_preserve_line_boundaries() {
        let code = "\n\n\n\n\n\n\n\n\n\n";
        let chunks = FunctionChunker::chunk(code, 3, 1);

        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.text.chars().all(|ch| ch == '\n'));
        }
    }
}
