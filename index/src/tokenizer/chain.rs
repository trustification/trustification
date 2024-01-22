use tantivy::tokenizer::{Token, TokenStream, Tokenizer};

pub trait ChainTokenizerExt: Sized {
    fn chain<T: Tokenizer>(self, next: T) -> ChainTokenizer<Self, T>;
}

impl<F: Tokenizer> ChainTokenizerExt for F {
    fn chain<T: Tokenizer>(self, second: T) -> ChainTokenizer<Self, T> {
        ChainTokenizer { first: self, second }
    }
}

#[derive(Clone)]
pub struct ChainTokenizer<F, S> {
    first: F,
    second: S,
}

impl<F, S> Tokenizer for ChainTokenizer<F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    type TokenStream<'a> = ChainTokenStream<'a, F, S>;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        ChainTokenStream {
            state: State::First,
            first: self.first.token_stream(text),
            second: self.second.token_stream(text),
            dummy: Token::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    First,
    Second,
    Done,
}

pub struct ChainTokenStream<'a, F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    first: F::TokenStream<'a>,
    second: S::TokenStream<'a>,
    state: State,
    dummy: Token,
}

impl<'a, F, S> TokenStream for ChainTokenStream<'a, F, S>
where
    F: Tokenizer,
    S: Tokenizer,
{
    fn advance(&mut self) -> bool {
        match self.state {
            State::First => {
                if self.first.advance() {
                    true
                } else {
                    self.state = State::Second;
                    self.advance()
                }
            }
            State::Second => {
                if self.second.advance() {
                    true
                } else {
                    self.state = State::Done;
                    false
                }
            }
            State::Done => false,
        }
    }

    fn token(&self) -> &Token {
        match self.state {
            State::First => self.first.token(),
            State::Second => self.second.token(),
            State::Done => &self.dummy,
        }
    }

    fn token_mut(&mut self) -> &mut Token {
        match self.state {
            State::First => self.first.token_mut(),
            State::Second => self.second.token_mut(),
            State::Done => &mut self.dummy,
        }
    }
}
