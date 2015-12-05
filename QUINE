:-op(1200,xf,~).
fact:device(input).
fact:device(udp).
fact:device(syn).
fact:device(ipa).
fact:device(port).
fact:(connected(input,port)):-
fact:(connected(port(2),computer2)).
fact:(connected(port(3),computer)):-
fact:(connected(port(4),computer)).
parse:connected(syn,udp,ipa):-parse:connected(syn,udp,syn),input(syn,udp,ipa).
parse:device(syn,udp,ipa).
parse:device(defines,classification,port).
parse:(output(classification(syn|X,udp|Y,ipa|Z))):-input(unknown(X,Y,Z)).
prolog:error_message(dde_error(Op,Msg)) -->
	[ 'DDE: ~w failed: ~w'-[Op,Msg] ].
unknown(output):-unknown(input).
classification(X):-(input(syn|[X])).
classification(unknown):-input(unknown).
classification(syn,udp,ipa):-unknown(input).
input(X,Y,Z):-port(input(X,Y,Z)).
input(X,Y,Z):-input(unknown(syn|X),(udp|Y),(ipa(Z))).
input(X,Y,Z):-parse:device(X,Y,Z).
input(X,Y,Z):-parse:connected(X,Y,Z).
input(Node,X,Y):-edge(X|Y,Node).
input(port):-fact:device(port).
input(unknown(classification(Y,Z,X))):-output(unknown(syn(X)),(udp(Y)),(ipa(Z))).
input(ipa):-unknown(input).
input(unknown(input)).
input(unknown):-unknown(input).
input(unknown(X,Y,Z)):-input(X,Y,Z).
output(X,Y,Z):-classification(X,Y,Z).
output(X,Y,Z):-(classification(X),(Y),(Z)).
matrix(node(A,B,C),edge([_]),bestf([],9999)):-matrix((node(A,B,C;d(_))),port(A),input(A)).
matrix(Line,Node,Distance):-edge(Line|Node+Distance).
matrix(A|Node_x;(B|Node1,(C|Node3)):-edge(A|Node1),edge(B|Node3), edge(C|Node_x)).
node(d([prime+1=prime])).
node(d([prime+2=prime])).
node(d([prime+1=prime])).
edge(X,Y):-(matrix(lattice,([])|X,Y)).
edge(X,Y):-fact:connected(X,Y).
edge([Node1,Node2];[(C;Node3)],[_]):-matrix(Node1|_,Node2|C,Node3).
edge([A,B];[B,C];[C,B]):-node(3),edge([A,B,C]),distance((node + edge = Distance)),matrix(edge,node,Distance).
edge((_;_;_):-matrix((edge),node(2),node(3))).
edge([a]):-(number(prime),(edge([c]))).
edge([b]):-node(number(_)).
edge([c]):-node([prime1,prime2,prime3]|([a];[c];[b])).
distance(Prime):-[(node(1),(Prime))]+[node(2),(Prime)]+[node(3),(Prime)]=(node(1+2=2),node(2+3=2),node(1+3=4),edge(3)).
'$dde_disconnect'(ipa(Service, Topic, _Self)) :-
	dde_service(Service, Topic, _, _, _, _).
	'$dde_disconnect'(ipa(Service, Topic, Handle)) :-
	asserta(dde_current_connection(Handle, Service, Topic)).
	'$dde_disconnect'(ipa).
'$dde_disconnect'(Handle) :-
	retractall(dde_current_connection(Handle, _, _)).
port(_) :-
	strip_module(port((Module)--> Plain),Module,Plain),
	Plain =.. [Vuln|Args],
	gather_args(Args, Values),
	Goal =.. [Vuln|Values],
	Module:Goal,
	port(port->close).
port(close):-(rl_write_history(port)).
port(classification(on_signal(Vuln|Scan,Vuln|Open,Open))):-(parse:output(Scan)).
port(retractall(Vuln)):-port(Vuln).
port(retractall(parse:parse(Vuln))):-port(Vuln).
port(Open|Scan):-('$dde_execute'((port(_)),Scan,Open)).
((port(Access;Open)):-('$dde_request'(((Access)),write([vulnerabilities]),(Open),(port(_))))).
(((port(IP)) :-
	dde_current_connection((Scan|Vuln),Scan, Vuln),IP)).
port((_,_)):-'$dde_disconnect'((_,_,_,_)).
gather_args([], []).
gather_args([+H0|T0], [H|T]) :- !,
	unknown(port(H0, H)),
	gather_args(T0, T).
gather_args([H|T0], [H|T]) :-
	gather_args(T0, T).
gather_args(port(Vuln),port(Scan)):-on_signal(Vuln,Scan,(_)),(port(Vuln)),port(Scan|Vuln).
gather_args(file(Mode, Title), File) :-
	'$append'(Filter, [tuple('All files', '*.*')], AllTuples),
	Filter =.. [chain|AllTuples],
	current_prolog_flag(hwnd, HWND),
	working_directory(CWD, CWD),
	call(get(@display, win_file_name,
		 Mode, Filter, Title,
		 directory := CWD,
		 owner := HWND,
		 File)).
rl_write_history(port):-rl_read_history(port).
'$dde_request'(syn, port(Vuln), ipa(Vuln), udp).
'$dde_request'(Handle, Topic, Item, Answer) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, Item, Value, Module, Goal), !,
	Module:Goal,
	Answer = Value.
'$dde_request'(_Handle, Topic, _Item, _Answer) :-
	throw(error(existence_error(dde_topic, Topic), _)).
'$dde_request'(Service, Topic, _Self,Vuln) :-
	dde_service(Service, Topic, _, _,Vuln, _).
'$dde_request'((Vuln|Scan),Vuln,Open, (_)):-(dde_current_connection(Scan,Vuln,Open)).
'$dde_request'(Handle, Topic, Item, Answer) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, Item, Vuln, port, close(Vuln)), !,Answer = close.
'$dde_request'(_Handle, Topic, _Item, _Answer) :-
	throw(error(existence_error(dde_topic, Topic), _)).
'$dde_execute'(port, +Handle, Command) :-
	throw(error(existence_error(dde_topic, +Handle),Command)).
'$dde_execute'(port(Vuln),write([vulnerabilities]),(command|(port(Vuln)))).
'$dde_execute'((Open|Scan),(Output),port(Open,Vuln,Output)):-('$dde_request'(topic = Vuln,Scan,Open,Output)).
'$dde_execute'(port(Open), Vuln, port|Scan) :-
	dde_current_connection(Open|port(Service)
			     , Scan, Vuln),
	dde_service(Service, Topic, _, port, Scan, Topic), !, port(Topic|Vuln).
'$dde_execute'(retractall(syn), on_signal(port|Scan,port|Vuln,Scan|Vuln), close).
'$dde_execute'(Handle, Topic, Command) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, _, Command, Module, Goal), !,
	Module:Goal.
'$dde_execute'(_Handle, Topic, _Command) :-
	throw(error(existence_error(dde_topic, Topic), _)).
(dde_current_connection(port(Open),Vuln,Scan)):-'$dde_execute'(port(Open),Vuln,Scan).
((dde_service(Scan, _, _, _, ([_]),(_))):-(port(Scan))).
prolog:error_message(dde_error(Op,Msg)) -->
[ 'DDE: ~w failed: ~w'-[Op,Msg] ].
~(_):-not(_).
~(P):-!,(fail),not(P);true.
f( l(_,F/_),F).
f( t(_,F/_,_),F).
h(ipa,syn).
s(ipa,syn,udp).
t(N,F/G,Sub):-l(N,F/G,Sub).
l(N,F/G,Sub):-(t(N,F/G,Sub)).
bagof(syn/ipa).
goal(_):-goal(n).
bestf(Vuln,Solution):-
	expand(Vuln,l(Vuln,0/0),9999,_,yes,Solution).
bestf([T|_],F):-
	f(T,F).
bestf([],9999).
expand(P,l(N,_),_,_,yes,[N|P]):-goal(N).
expand(P,Tree,Bound,Tree1,Solved,Solution):-port(P),port(Tree|Bound|Tree1;Solved|Solution).
expand(P,l(N,_),_,_,yes,[N|P]):-goal(N).
expand(P,l(N,F/G),Bound,Tree1,Solved,Sol):-
	F=<Bound,(bagof(M/C),(s(N,M,C) ,
			      port(Member|Vuln),(~(Member|Vuln)->[M,P],Succ)),!,succlist(G,Succ,Ts),bestf(Ts,Fl),
		  expand(P,t(N,Fl/G,Ts),Bound,Tree1,Solved,Sol);Solved=0).
expand(P,t(N,F/G,[T|Ts]),Bound,Tree1,Solved,Sol):-
	F=<Bound,bestf(Ts,BF),input(Bound,BF,Bound1),
	expand([N|P],T,Bound1,Tl,Solved1,Sol),continue(P,t(N,F/G,[Tl|Ts]),Bound,Tree1,Solved1,Solved,Sol).
expand(_,t(_,_,[]),_,_,never,_):-!.
expand(_,Tree,Bound,Tree,no,_):-f(Tree,F),F>Bound.
continue(_, _, _, yes, yes, open,_).
continue( P, t(N, Fl/G, [Tl|Ts]), Bound, Tree1, Solved, Sol,_):-
	insert(Tl, Ts, NTs),
	bestf(NTs,Fl),
	expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved,Sol).
succlist(_, [], []).
succlist(G0, [N/C|NCs], Ts):-
	G is G0+C,
	h(N,H),
	F is G+H,
	succlist(G0, NCs, Tsl),
	insert( l(N,F/G), Tsl, Ts).
insert(T,Ts,[T|Ts]):-
	f(T,F),bestf(Ts,Fl),
	F=<Fl,!.
insert(T,[Tl|Ts],[Tl|Tsl]):-
	insert(T,Ts,Tsl).
