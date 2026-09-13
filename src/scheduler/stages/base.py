"""Base pipeline stage interface.

Only the fetch and parse stages are dispatched through ``run()``; the
remaining stages are invoked directly by the runner with their explicit
methods (``apply``, ``preprocess``, ``validate_by_list``, ...), which carry
their own arguments. The base class therefore stays as a lightweight marker
with a non-abstract fallback: making ``run`` abstract would force every
stage to carry a stub ``run`` it never uses, and deleting the class outright
would break ``isinstance`` checks in tests.
"""

from __future__ import annotations

from src.scheduler.context import PipelineContext, PipelineState


class PipelineStage:
    """A single stage of the pipeline.

    Concrete stages may accept ``run(state, context)`` or the older
    ``run(state)`` form. Callers that go through the stage interface always
    pass both arguments; older code paths that call ``state``-only methods
    continue to work because ``context`` is optional here.
    """

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        """Execute the stage and return the updated state.

        The default body deliberately raises instead of returning ``None``:
        a stage dispatched through ``run()`` without overriding it is a
        wiring mistake, and a silent ``None`` would surface later as an
        ``AttributeError`` on the returned value.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not implement run(); the runner "
            "calls this stage's explicit method instead.",
        )
