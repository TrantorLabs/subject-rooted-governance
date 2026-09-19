-------------------------- MODULE P2_Observability --------------------------
EXTENDS Naturals, FiniteSets
VARIABLE world
Worlds == [actor : 0..1, prior : 0..1, current : 0..1]
Init == world \in Worlds
Next == UNCHANGED world
WeakOnline(w) == <<TRUE, "read">>
StrongOnline(w) == <<TRUE, "read", w.actor>>
Decision(w) == IF w.actor = 0 THEN "deny" ELSE "allow"
WeakHistory(w) == <<"x", w.current>>
StrongHistory(w) == <<"x", w.current, w.prior>>
OnlineWitness == \E a,b \in Worlds : WeakOnline(a) = WeakOnline(b) /\ Decision(a) # Decision(b)
HistoryWitness == \E a,b \in Worlds : WeakHistory(a) = WeakHistory(b) /\ a.prior # b.prior
OnlineResolved == \A a,b \in Worlds : StrongOnline(a) = StrongOnline(b) => Decision(a) = Decision(b)
HistoryResolved == \A a,b \in Worlds : StrongHistory(a) = StrongHistory(b) => a.prior = b.prior
=============================================================================
