from contextlib import nullcontext
from types import SimpleNamespace as NS
import unittest

from .cuda_bf16_probe import verify


class Tensor:
    def __init__(self,size,dtype,index,val):
        self.size,self.dtype,self.index,self.val=size,dtype,index,val
    def __add__(self,other):
        return Tensor(self.size,self.dtype,self.index,self.val+other.val)
    def __matmul__(self,other):
        return Tensor(self.size,self.dtype,self.index,self.val*other.val*2)
    def get_device(self):
        return self.index
    def cpu(self):
        return self
    def tolist(self):
        return [[self.val,self.val],[self.val,self.val]]


class ProbeTest(unittest.TestCase):
    def fake(self,synchronize=lambda i:None,bf16=True,wrong_index=False):
        return NS(__version__="fixture",version=NS(cuda="12.8"),bfloat16="bf16",inference_mode=nullcontext,
          full=lambda shape,val,device,dtype:Tensor(shape,dtype,0 if wrong_index else int(device[-1]),val),
          cuda=NS(is_available=lambda:True,device_count=lambda:2,get_arch_list=lambda:["sm_120"],
            device=lambda _:nullcontext(),get_device_name=lambda _:"fixture",
            get_device_capability=lambda _:(12,0),is_bf16_supported=lambda **kwargs:bf16,
            synchronize=synchronize))

    def test_actual_operation_and_explicit_sync_per_device(self):
        events=[]
        report=verify(self.fake(synchronize=events.append),2,read_driver=lambda:"580.1")
        self.assertEqual(events,[0,1])
        self.assertEqual(report["nvidia_driver"],"580.1")
        self.assertEqual([v["compute_capability"] for v in report["device_results"]],[[12,0],[12,0]])

    def test_failed_kernel_native_bf16_or_device_refuses_launch(self):
        def fail(i):
            if i==1:
                raise RuntimeError("synthetic asynchronous kernel error")
        for fake,index in ((self.fake(synchronize=fail),1),(self.fake(bf16=False),0),(self.fake(wrong_index=True),1)):
            with self.subTest(index=index),self.assertRaisesRegex(RuntimeError,f"device {index}"):
                verify(fake,2,read_driver=lambda:"580.1")
