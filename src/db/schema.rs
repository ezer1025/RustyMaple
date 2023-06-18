use diesel::table;

table! {
    users(id, username) {
        id -> Integer,
        username -> Varchar,
        is_female -> Bool,
        is_admin -> Bool,
        logged_in -> Bool,
        password -> Varchar,
        salt -> Bytea,
        pin_code -> Nullable<Varchar>,
        creation_date -> Timestamp,
        ban_reason -> SmallInt,
        ban_reset_date -> Timestamp,
        mute_reason -> SmallInt,
        mute_reset_date -> Timestamp,
    }
}