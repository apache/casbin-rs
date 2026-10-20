use crate::push_index_if_explain;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum EffectKind {
    Allow = 0,
    Indeterminate = 1,
    Deny = 2,
}

pub trait Effector: Send + Sync {
    fn new_stream(&self, expr: &str, cap: usize) -> Box<dyn EffectorStream>;
}

pub trait EffectorStream: Send + Sync {
    fn next(&self) -> bool;
    #[cfg(feature = "explain")]
    fn explain(&self) -> Option<Vec<usize>>;
    fn push_effect(&mut self, eft: EffectKind) -> bool;
}

#[derive(Clone)]
pub struct DefaultEffectStream {
    done: bool,
    res: bool,
    expr: String,
    idx: usize,
    cap: usize,
    #[cfg(feature = "explain")]
    expl: Vec<usize>,
}

#[derive(Default)]
pub struct DefaultEffector;

impl Effector for DefaultEffector {
    fn new_stream(&self, expr: &str, cap: usize) -> Box<dyn EffectorStream> {
        assert!(cap > 0);

        let res = match expr {
            "some(where (p_eft == allow))"
            | "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
            | "priority(p_eft) || deny"
            | "subjectPriority(p_eft) || deny" => false,
            "!some(where (p_eft == deny))" => true,
            _ => panic!("unsupported effect: `{}`", expr),
        };

        Box::new(DefaultEffectStream {
            done: false,
            res,
            expr: expr.to_owned(),
            cap,
            idx: 0,
            #[cfg(feature = "explain")]
            expl: Vec::with_capacity(10),
        })
    }
}

impl EffectorStream for DefaultEffectStream {
    #[inline]
    fn next(&self) -> bool {
        assert!(self.done);
        self.res
    }

    #[cfg(feature = "explain")]
    #[inline]
    fn explain(&self) -> Option<Vec<usize>> {
        assert!(self.done);
        if self.expl.is_empty() {
            None
        } else {
            Some(self.expl.clone())
        }
    }

    fn push_effect(&mut self, eft: EffectKind) -> bool {
        if self.expr == "some(where (p_eft == allow))" {
            if eft == EffectKind::Allow {
                self.done = true;
                self.res = true;

                push_index_if_explain!(self);
            }
        } else if self.expr
            == "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
        {
            if eft == EffectKind::Allow {
                self.res = true;

                push_index_if_explain!(self)
            } else if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;

                #[cfg(feature = "explain")]
                self.expl.clear();
                push_index_if_explain!(self)
            }
        } else if self.expr == "!some(where (p_eft == deny))" {
            if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;

                push_index_if_explain!(self)
            }
        } else if (self.expr == "priority(p_eft) || deny"
            || self.expr == "subjectPriority(p_eft) || deny")
            && eft != EffectKind::Indeterminate
        {
            self.res = eft == EffectKind::Allow;

            self.done = true;

            push_index_if_explain!(self)
        }

        if self.idx + 1 == self.cap {
            self.done = true;
            self.idx = self.cap;
        } else {
            self.idx += 1;
        }

        self.done
    }
}
