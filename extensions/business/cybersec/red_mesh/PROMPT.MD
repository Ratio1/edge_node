[We have the following new features that must be implemented in RedMesh red-teaming pentesting framework API:
- better monitoring of worker status and job progress
- possibility to select certain types of tests instead of running all tests (we already have the option to exclude certain ports)
- per-worker port distribution strategies: "slice" each Ratio1 worker that runs RedMesh will receive a "slice" or "mirror" when all workers get the same port range
- for each local-worker (thread configured via `nr_local_workers` parameter of the `_launch_job` method) we want to have a parameter called PORT_ORDER (sequential or shuffle), that would define if we want to iterate through ports sequentially or shuffle. In on_inti order ports_to_scan per port_order.
- run mode: singlepass (one time scan) vs continuous monitoring (scanning continuously). Don't forget to keep the stats about each run .
- for continuous job, make it possible to configure the scheduling
- Add parameters for configuring Pacing/jitter (“Dune sand walking”) to slow/space out scans by adding random pauses

I want you to describe the architecture as minimalistic as possible. Don't add unnecessary thing. It should follow the Keep It Simple Stuping principles.
It should be simple and functional.


Review the TODO_A.md and TODO_B.md and create a final TODO_C.md that proposes a action plan with clear architectural steps to implement these features (no code as TODO_B.md currently wrongly has incorrect code)
Please, focus on architecture, feature and planning them. 

Use the maximum amount of ultrathink. Take all the time you need. It's much better if you do too much research and thinking than not enough.