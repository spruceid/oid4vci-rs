macro_rules! field_getters {
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < bool >) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<bool> {
            $zero.$field
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < bool > { $($body:tt)+ }) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<bool> {
            $($body)+
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < DateTime < Utc >>) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<DateTime<Utc>> {
            $zero.$field
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < DateTime < Utc >> { $($body:tt)+ }) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<DateTime<Utc>> {
            $($body)+
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < $type:ty >) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<&$type> {
            $zero.$field.as_ref()
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident Option < $type:ty > { $($body:tt)+ }) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> Option<$type> {
            $($body)+
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident DateTime < Utc >) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> DateTime<Utc> {
            $zero.$field
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident $type:ty) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> &$type {
            &$zero.$field
        }
    };
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $field:ident $type:ty { $($body:tt)+ }) => {
        #[doc = $doc]
        $vis fn $field(&$self) -> $type {
            $($body)+
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < bool >) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<bool> {
            $zero.$field()
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < bool > { $($body:tt)+ }) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<bool> {
            $($body)+
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < DateTime < Utc >>) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<DateTime<Utc>> {
            $zero.$field()
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < DateTime < Utc >> { $($body:tt)+ }) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<DateTime<Utc>> {
            $($body)+
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < $type:ty >) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<&$type> {
            $zero.$field()
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() Option < $type:ty > { $($body:tt)+ }) => {
        #[doc = $doc]
        fn $field(&$self) -> Option<$type> {
            $($body)+
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() DateTime < Utc >) => {
        #[doc = $doc]
        fn $field(&$self) -> DateTime<Utc> {
            $zero.$field()
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() $type:ty) => {
        #[doc = $doc]
        fn $field(&$self) -> &$type {
            &$zero.$field()
        }
    };
    (@case [$doc:expr] $self:ident [$zero:expr] $field:ident() $type:ty { $($body:tt)+ }) => {
        #[doc = $doc]
        fn $field(&$self) -> $type {
            $($body)+
        }
    };
    // Main entry points
    (
        $vis:vis $self:ident [$zero:expr] [$doc:expr] {
            $(
                $field:ident[$($entry:tt)+] [$doc_field:expr],
            )+
        }
    ) => {
        $(
            field_getters![
                @case
                [concat!("Returns the `", $doc_field, "` ", $doc, ".")]
                $vis $self [$zero] $field $($entry)+
            ];
        )+
    };
    (
        $vis:vis $self:ident [$zero:expr]() [$doc:expr] {
            $(
                $field:ident[$($entry:tt)+] [$doc_field:expr],
            )+
        }
    ) => {
        $(
            field_getters![
                @case
                [concat!("Returns the `", $doc_field, "` ", $doc, ".")]
                $vis $self [$zero] $field() $($entry)+
            ];
        )+
    };
}

macro_rules! field_setters {
    (@case [$doc:expr] $vis:vis $self:ident [$zero:expr] $setter:ident $field:ident $type:ty [$doc_field:expr]) => {
        field_setters![
            @case2
            [concat!("Sets the `", $doc_field, "` ", $doc, ".")]
            $vis $self [$zero] $setter $field $type
        ];
    };
    (@case2 [$doc:expr] $vis:vis $self:ident [$zero:expr] $setter:ident $field:ident $type:ty) => {
        #[doc = $doc]
        $vis fn $setter(
            mut $self,
            $field: $type
        ) -> Self {
            $zero.$field = $field;
            $self
        }
    };
    // Main entry point
    (
        $vis:vis $self:ident [$zero:expr] [$doc:expr] {
            $setter:ident -> $field:ident[$($entry:tt)+] [$doc_field:expr]
        }
    ) => {
        field_setters![
            @case [$doc] $vis $self [$zero] $setter $field $($entry)+ [$doc_field]
        ];
    };
}

macro_rules! field_getters_setters {
    (
        @single $vis:vis $self:ident [$zero:expr] [$doc:expr]
        [$setter:ident -> $field:ident[$($entry:tt)+] [$field_doc:expr], $($rest:tt)*]
    ) => {
        field_getters![$vis $self [$zero] [$doc] { $field[$($entry)+] [$field_doc], }];
        field_setters![
            $vis $self [$zero] [$doc] { $setter -> $field[$($entry)+] [$field_doc] }
        ];
        field_getters_setters![@single $vis $self [$zero] [$doc] [$($rest)*]];
    };
    (
        @single $vis:vis $self:ident [$zero:expr]() [$doc:expr]
        [$setter:ident -> $field:ident[$($entry:tt)+] [$field_doc:expr], $($rest:tt)*]
    ) => {
        field_getters![$vis $self [$zero]() [$doc] { $field[$($entry)+] [$field_doc], }];
        field_setters![
            $vis $self [$zero] [$doc] { $setter -> $field[$($entry)+] [$field_doc] }
        ];
        field_getters_setters![@single $vis $self [$zero]() [$doc] [$($rest)*]];
    };
    (
        @single $vis:vis $self:ident [$zero:expr] [$doc:expr]
        [$setter:ident -> $field:ident[$($entry:tt)+], $($rest:tt)*]
    ) => {
        field_getters![$vis $self [$zero] [$doc] { $field[$($entry)+] [stringify!($field)], }];
        field_setters![
            $vis $self [$zero] [$doc] { $setter -> $field[$($entry)+] [stringify!($field)] }
        ];
        field_getters_setters![@single $vis $self [$zero] [$doc] [$($rest)*]];
    };
    (
        @single $vis:vis $self:ident [$zero:expr]() [$doc:expr]
        [$setter:ident -> $field:ident[$($entry:tt)+], $($rest:tt)*]
    ) => {
        field_getters![$vis $self [$zero]() [$doc] { $field[$($entry)+] [stringify!($field)], }];
        field_setters![
            $vis $self [$zero] [$doc] { $setter -> $field[$($entry)+] [stringify!($field)] }
        ];
        field_getters_setters![@single $vis $self [$zero]() [$doc] [$($rest)*]];
    };
    // Base case.
    (@single $vis:vis $self:ident [$zero:expr] [$doc:expr] []) => {};
    // Main entry points.
    (
        $vis:vis $self:ident [$zero:expr] [$doc:expr] {
            $setter:ident -> $field:ident[$($entry:tt)+] $($rest:tt)*
        }
    ) => {
        field_getters_setters![
            @single
            $vis $self [$zero] [$doc] [$setter -> $field[$($entry)+] $($rest)*]
        ];
    };
    (
        $vis:vis $self:ident [$zero:expr]() [$doc:expr] {
            $setter:ident -> $field:ident[$($entry:tt)+] $($rest:tt)*
        }
    ) => {
        field_getters_setters![
            @single
            $vis $self [$zero]() [$doc] [$setter -> $field[$($entry)+] $($rest)*]
        ];
    };
}
