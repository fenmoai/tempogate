// Package state is intentionally empty of types and interfaces.
//
// We follow a per-consumer state-interface convention: each package that
// reads or writes persistent state defines its OWN narrow interface in its
// own package, listing only the methods that package needs. The eventual
// concrete store (sqlite.Store) satisfies all of them — structurally where
// the names line up, and via a thin adapter where the consumer prefers
// short, domain-local names. No package imports state/.
//
// # Method-naming convention
//
// Consumer interfaces favour short, domain-local method names that read
// naturally inside the consumer package — Save, ByID, List, MarkRevoked on
// admin.KeyRegistry. The concrete sqlite.Store uses domain-prefixed names
// (SaveIntegrationKey, IntegrationKeyByID, ListIntegrationKeys, ...) so
// multiple consumers can coexist on the same struct without identifier
// collisions (Go has no method overloading).
//
// Where the two sets line up, sqlite/fx.go binds via fx.As(new(Foo)) on
// *Store directly (see keys.KeyStore, oidc.AuthRequestStore — those
// interfaces happen to use the prefixed names because nothing else needs
// "Save" or "Consume" at the time of writing). Where the consumer prefers
// short names, sqlite/ adds a thin adapter struct (see
// state/sqlite/admin_adapter.go) and binds via a constructor in sqlite/fx.go.
//
// # Adding a new consumer
//
//  1. Define `type fooStore interface { … }` in your package (lowercase if
//     only your package uses it). Use whichever method names read best in
//     your package — short names are fine, prefixed names are fine.
//  2. Implement matching methods on `sqlite.Store` under prefixed names
//     (SaveFoo, FooByID, ListFoos, ...) so they don't collide with another
//     consumer's identically named method.
//  3. Wire your interface to *Store in state/sqlite/fx.go: either
//     fx.As(new(YourInterface)) if your names happen to match, or a small
//     adapter struct + constructor if they don't.
//  4. Inject the store into your fx graph as your local interface type.
//  5. Do NOT import state/.
//
// See keys/store.go for the seed example (prefixed names → fx.As) and
// admin/store.go + state/sqlite/admin_adapter.go for the short-names + shim
// pattern.
package state
