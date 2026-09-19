------------------------------ MODULE P2_Core ------------------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANT Fault
VARIABLES stage, revoked, cached, resolved, allow, effects, op, saved, afterRevoke
vars == <<stage, revoked, cached, resolved, allow, effects, op, saved, afterRevoke>>
Init == /\ stage = 0 /\ revoked = FALSE /\ cached = FALSE
        /\ resolved = 0 /\ allow = FALSE /\ effects = 0
        /\ op = 0 /\ saved = FALSE /\ afterRevoke = FALSE
Start == /\ stage = 0 /\ stage' = 1 /\ revoked' \in BOOLEAN
         /\ UNCHANGED <<cached, resolved, allow, effects, op, saved, afterRevoke>>
Submit == /\ stage = 1 /\ stage' = 2
          /\ cached' = IF Fault = "StaleState" THEN FALSE ELSE revoked
          /\ resolved' = IF Fault = "SubjectConfusion" THEN 1 ELSE 0
          /\ UNCHANGED <<revoked, allow, effects, op, saved, afterRevoke>>
Admit == /\ stage = 2 /\ stage' = 3
         /\ allow' = IF Fault = "AuthorityMismatch" THEN TRUE ELSE (~cached \/ resolved = 1)
         /\ afterRevoke' = revoked
         /\ UNCHANGED <<revoked, cached, resolved, effects, op, saved>>
Execute == /\ stage = 3 /\ stage' = 4
           /\ effects' = IF allow \/ Fault = "DenyThenEffect" THEN 1 ELSE 0
           /\ op' = IF (allow \/ Fault = "DenyThenEffect") /\ Fault = "Substitution" THEN 1 ELSE 0
           /\ saved' = ((allow \/ Fault = "DenyThenEffect") /\ Fault # "ProvenanceLoss")
           /\ UNCHANGED <<revoked, cached, resolved, allow, afterRevoke>>
Bypass == /\ stage = 2 /\ Fault = "Bypass" /\ stage' = 4
          /\ effects' = 1 /\ afterRevoke' = revoked
          /\ UNCHANGED <<revoked, cached, resolved, allow, op, saved>>
Replay == /\ stage = 4 /\ Fault = "Replay" /\ allow /\ effects = 1
          /\ effects' = 2
          /\ UNCHANGED <<stage, revoked, cached, resolved, allow, op, saved, afterRevoke>>
Next == Start \/ Submit \/ Admit \/ Execute \/ Bypass \/ Replay
Spec == Init /\ [][Next]_vars
TypeOK == /\ stage \in 0..4 /\ revoked \in BOOLEAN /\ cached \in BOOLEAN
          /\ resolved \in 0..1 /\ allow \in BOOLEAN /\ effects \in 0..2
          /\ op \in 0..1 /\ saved \in BOOLEAN /\ afterRevoke \in BOOLEAN
O1 == stage < 4 \/ effects = 0 \/ (saved /\ resolved = 0)
O2 == stage < 4 \/ effects = 0 \/ (allow /\ resolved = 0 /\ ~afterRevoke /\ op = 0 /\ effects <= 1)
O3 == stage < 4 \/ ~afterRevoke \/ effects = 0
=============================================================================
