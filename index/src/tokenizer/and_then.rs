use tantivy::tokenizer::{Token, TokenStream, Tokenizer};

#[derive(Clone)]
pub struct AndThenTokenizer<F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    first: F,
    second: S,
}

impl<F, S> AndThenTokenizer<F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    pub fn new(first: F, second: S) -> Self {
        Self { first, second }
    }
}

impl<F, S> Tokenizer for AndThenTokenizer<F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    type TokenStream<'a> = AndThenTokenStream<'a, F, S>;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        AndThenTokenStream {
            first: self.first.token_stream(text),
            second: self.second.clone(),
            running: false,
            state: vec![],
            dummy: Token::default(),
        }
    }
}

pub struct AndThenTokenStream<'a, F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    // the first token stream
    first: F::TokenStream<'a>,
    // the second tokenizer to apply to tokens of the first stream
    second: S,
    // the second level list of tokens, extracted from the current first stream token
    state: Vec<Token>,
    // Flag if the current state is "running" or not. This is required as there will be
    // a call to advance() before the getting the first token.
    running: bool,
    // a dummy value for which we can return a reference when we have nothing
    dummy: Token,
}

impl<'a, F, S> TokenStream for AndThenTokenStream<'a, F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    fn advance(&mut self) -> bool {
        loop {
            if self.running {
                self.state.pop();
            } else {
                self.running = true;
            }

            // take the next element from the second stream
            if !self.state.is_empty() {
                // we got content in our second level stream
                return true;
            }

            // we exhausted the second stream (or we didn't have one)
            if !self.first.advance() {
                // but we exhausted the first stream, so we are done
                return false;
            }

            // we take the current (first) token and collect the token stream using the second tokenizer
            // FIXME: that's not ideal, as we buffer the full second token stream outcome
            let mut stream = self.second.token_stream(&self.first.token().text);
            while let Some(token) = stream.next() {
                self.state.push(token.clone());
            }
            self.running = false;
            // now re-try the loop
        }
    }

    fn token(&self) -> &Token {
        let len = self.state.len();
        if len > 0 {
            &self.state[len - 1]
        } else {
            &self.dummy
        }
    }

    fn token_mut(&mut self) -> &mut Token {
        let len = self.state.len();
        if len > 0 {
            &mut self.state[len - 1]
        } else {
            &mut self.dummy
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tantivy::tokenizer::{NgramTokenizer, SimpleTokenizer};

    #[derive(Clone)]
    pub(crate) struct EmptyTokenizer;

    impl Tokenizer for EmptyTokenizer {
        type TokenStream<'a> = EmptyTokenStream;
        fn token_stream(&mut self, _text: &str) -> EmptyTokenStream {
            EmptyTokenStream::default()
        }
    }

    #[derive(Default)]
    pub struct EmptyTokenStream {
        token: Token,
    }

    impl TokenStream for EmptyTokenStream {
        fn advance(&mut self) -> bool {
            false
        }

        fn token(&self) -> &super::Token {
            &self.token
        }

        fn token_mut(&mut self) -> &mut super::Token {
            &mut self.token
        }
    }

    fn assert_and_then<'a>(
        first: impl Tokenizer,
        second: impl Tokenizer,
        input: &str,
        expected: impl IntoIterator<Item = &'a str>,
    ) {
        let mut and_then = AndThenTokenizer::new(first, second);
        let mut stream = and_then.token_stream(input);
        let mut result = vec![];
        while let Some(token) = stream.next() {
            result.push(token.text.to_string());
        }
        let expected = expected.into_iter().collect::<Vec<_>>();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_simple() {
        assert_and_then(
            SimpleTokenizer::default(),
            NgramTokenizer::prefix_only(1, 2).unwrap(),
            "foo bar",
            ["fo", "f", "ba", "b"],
        );
    }

    #[test]
    fn test_first_empty() {
        assert_and_then(EmptyTokenizer, SimpleTokenizer::default(), "foo bar", []);
    }

    #[test]
    fn test_second_empty() {
        assert_and_then(SimpleTokenizer::default(), EmptyTokenizer, "foo bar", []);
    }

    #[test]
    fn test_two_empty() {
        assert_and_then(SimpleTokenizer::default(), EmptyTokenizer, "foo bar", []);
    }
}
