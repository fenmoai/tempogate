// Package state is intentionally empty of types and interfaces.
//
// We follow a per-consumer state-interface convention: each package that
// reads or writes persistent state defines its OWN narrow interface in its
// own package, listing only the methods that package needs. The eventual
// concrete store (E7.2: sqlite.Store) satisfies all of them structurally
// without any package importing state/.
//
// To add a new consumer:
//
//  1. Define `type fooStore interface { … }` in your package (lowercase if
//     only your package uses it).
//  2. Implement matching methods on `sqlite.Store`.
//  3. Inject the store into your fx graph as your local interface type.
//  4. Do NOT import state/.
//
// See keys/store.go for the seed example.
package state
