API Reference
=============

Managers
--------

.. autoclass:: apatchy.managers.config_manager.ConfigManager
   :members:

.. autoclass:: apatchy.managers.module_manager.ModuleManager
   :members:

.. autoclass:: apatchy.managers.build_manager.BuildManager
   :members:

.. autoclass:: apatchy.managers.dev_manager.DevManager
   :members:

.. autoclass:: apatchy.managers.bug_manager.BugManager
   :members:

.. autoclass:: apatchy.managers.fuzz_manager.GrammarSeedGenerator
   :members:

.. autoclass:: apatchy.managers.fuzz_manager.FuzzManager
   :members:

.. autoclass:: apatchy.managers.mutator_manager.MutatorManager
   :members:

.. autoclass:: apatchy.managers.toolchain_manager.ToolchainManager
   :members:

.. autoclass:: apatchy.managers.report_manager.ReportManager
   :members:

.. autoclass:: apatchy.managers.introspector_manager.IntrospectorManager
   :members:

Core
----

.. autoclass:: apatchy.core.process_runner.ProcessRunner
   :members:

.. autoclass:: apatchy.core.downloader.Downloader
   :members:

.. autoclass:: apatchy.core.harness.HarnessBuilder
   :members:

Toolchain
---------

.. autoclass:: apatchy.core.toolchain.base.DepStatus
   :members:

.. autoclass:: apatchy.core.toolchain.base.ToolchainTool
   :members:

.. autoclass:: apatchy.core.toolchain.simple.BinaryTool
   :members:

.. autoclass:: apatchy.core.toolchain.simple.PkgOrConfigTool
   :members:

.. autoclass:: apatchy.core.toolchain.simple.HeaderOrPkgTool
   :members:

.. autoclass:: apatchy.core.toolchain.afl.AflTool
   :members:

.. autoclass:: apatchy.core.toolchain.llvm.LlvmTool
   :members:

.. autoclass:: apatchy.core.toolchain.libtool.LibtoolTool
   :members:

Misc
----

.. autoclass:: apatchy.config.Config
   :members:

.. autoclass:: apatchy.bugs.base.Bug
   :members:

.. autoclass:: apatchy.compat.CompatEntry
   :members:

.. autoclass:: apatchy.compat.CompatResult
   :members:

.. autoclass:: apatchy.utils.build_tree.AlternateBuildTree
   :members:

.. autoclass:: apatchy.utils.ui.UI
   :members:

.. autoclass:: apatchy.method_dispatcher.MethodDispatcher
   :members:
