use diesel::table;

table! {
    users {
        id -> Integer,
        username -> Varchar,
        is_female -> Bool,
        is_admin -> Bool,
        logged_in -> Bool,
        password -> Varchar,
        salt -> Bytea,
        creation_date -> Timestamp,
        ban_reason -> SmallInt,
        ban_reset_date -> Timestamp,
        mute_reason -> SmallInt,
        mute_reset_date -> Timestamp,
    }
}