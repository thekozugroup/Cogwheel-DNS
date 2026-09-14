//! One declaration per stored record.
//!
//! A record is a struct, the `SELECT` list that fills it and the function that reads a row into
//! it — three things that have to agree on field *order* or a column lands silently in the wrong
//! field. Written out three times per table they eventually will not agree, so they are written
//! once here instead.

/// Declare a record: the struct, `COLUMNS`, and `from_row` reading them in that order.
///
/// Joined projections (a rule and its device's name) name their columns in SQL rather than through
/// `COLUMNS`, because the column names there need table qualifiers the field names cannot carry.
/// `from_row` is positional, so it reads those the same way.
macro_rules! record {
    // `<Name> from "<table>"` also generates the two readers every list-and-get pair was
    // spelling out: the `SELECT` list, the table and `from_row` have to agree, and writing
    // them at each call site is three more chances for them not to.
    ($(#[$outer:meta])* $name:ident from $table:literal
        { $($(#[$inner:meta])* $field:ident: $type:ty),+ $(,)? }) => {
        record! { $(#[$outer])* $name { $($(#[$inner])* $field: $type),+ } }

        impl $name {
            /// Every row matching `tail`, a clause appended after `FROM <table>`.
            fn all<P: rusqlite::Params>(
                connection: &rusqlite::Connection,
                tail: &str,
                params: P,
            ) -> Result<Vec<Self>, $crate::StorageError> {
                $crate::repo::collect(
                    connection,
                    &format!("SELECT {} FROM {} {tail}", Self::COLUMNS, $table),
                    params,
                    Self::from_row,
                )
            }

            /// The one row matching `tail`, or `None` when there is none.
            #[allow(dead_code, reason = "not every table is ever read one row at a time")]
            fn one<P: rusqlite::Params>(
                connection: &rusqlite::Connection,
                tail: &str,
                params: P,
            ) -> Result<Option<Self>, $crate::StorageError> {
                use rusqlite::OptionalExtension;
                Ok(connection
                    .query_row(
                        &format!("SELECT {} FROM {} {tail}", Self::COLUMNS, $table),
                        params,
                        Self::from_row,
                    )
                    .optional()?)
            }
        }
    };

    ($(#[$outer:meta])* $name:ident { $($(#[$inner:meta])* $field:ident: $type:ty),+ $(,)? }) => {
        $(#[$outer])*
        #[derive(Debug, Clone, serde::Serialize)]
        pub struct $name {
            $($(#[$inner])* pub $field: $type),+
        }

        impl $name {
            /// This record's columns, in `from_row` order.
            #[allow(dead_code, reason = "joined projections spell their own column list")]
            pub(crate) const COLUMNS: &'static str = stringify!($($field),+);

            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                let mut column = 0;
                $(let $field = { let value = row.get(column)?; column += 1; value };)+
                let _ = column;
                Ok(Self { $($field),+ })
            }
        }
    };
}
